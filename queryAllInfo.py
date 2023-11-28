import re
import time
import requests
import os
from lxml import html
import json

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/wxpic,image/tpg,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    "content-type": "application/json"
  }
queryUrl = "https://hackerone.com/graphql"

def check_title(title, keywords):
    for keyword in keywords:
        if len(keyword.split()) == 1:
            for word in title.split():
                if word == keyword:
                    return True
        else:
            if keyword in title:
                return True
    return False

def clean_title(title):
    return ' '.join(title.split()).lower().replace('-', ' ').replace('—', ' ').replace(',', '').replace('.', '') \
        .replace(':', '').replace(';', '')

def top_by_bug_type(reports, keywords):
    return [report for report in reports if check_title(clean_title(report['title']), keywords)]

def filterMobileReports(reports) :
    return top_by_bug_type(reports, ['mobile', 'android', 'ios', 'apk'])

def queryOnce(fromInt, sizeInt) :
    data = {
        "operationName":"HacktivitySearchQuery",
        "variables":{
            "queryString":"*:*",
            "size":sizeInt,
            "from":fromInt,
            "sort":{
                "field":"disclosed_at",
                "direction":"DESC"
            },
            "product_area":"hacktivity",
            "product_feature":"overview"
        },
        "query":"query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {\n  me {\n    id\n    __typename\n  }\n  search(\n    index: HacktivityReportIndexService\n    query_string: $queryString\n    from: $from\n    size: $size\n    sort: $sort\n  ) {\n    __typename\n    total_count\n    nodes {\n      __typename\n      ... on HacktivityReportDocument {\n        id\n        reporter {\n          id\n          name\n          username\n          ...UserLinkWithMiniProfile\n          __typename\n        }\n        cve_ids\n        cwe\n        severity_rating\n        upvoted: upvoted_by_current_user\n        report {\n          id\n          databaseId: _id\n          title\n          substate\n          url\n          disclosed_at\n          report_generated_content {\n            id\n            hacktivity_summary\n            __typename\n          }\n          __typename\n        }\n        votes\n        team {\n          handle\n          name\n          medium_profile_picture: profile_picture(size: medium)\n          url\n          id\n          currency\n          ...TeamLinkWithMiniProfile\n          __typename\n        }\n        total_awarded_amount\n        latest_disclosable_action\n        latest_disclosable_activity_at\n        __typename\n      }\n    }\n  }\n}\n\nfragment UserLinkWithMiniProfile on User {\n  id\n  username\n  __typename\n}\n\nfragment TeamLinkWithMiniProfile on Team {\n  id\n  handle\n  name\n  __typename\n}\n"
    }
    json_data = json.dumps(data)
    response = requests.post(queryUrl, headers=HEADERS, data=json_data)
    content = response.text
    contentDict = json.loads(content)
    retList = list()
    for item in contentDict["data"]["search"]["nodes"] :
        if not isinstance(item, dict) :
            continue
        report = item["report"]
        if report["report_generated_content"] != None :
            summary = report["report_generated_content"]["hacktivity_summary"]
        else :
            summary = ""
        retList.append({
            "title":report["title"],
            "substate":report["substate"],
            "url":report["url"],
            "cwe":item["cwe"],
            "severity_rating":item["severity_rating"],
            "cve_ids":item["cve_ids"],
            "bounty":item["total_awarded_amount"],
            "votes":item["votes"],
            "hacktivity_summary": summary
        }) 
    return retList

def queryAllWithType(fromInt, maxsize, filterFunc) :
    retList = list()
    for i in range(fromInt, maxsize, 25) :
        tmpLists = queryOnce(i, 25)
        # print([ item["title"] for item in tmpLists ])
        retList.extend(filterFunc(tmpLists))
    return retList

if __name__ == "__main__" :
    f = open("./output.json", "w", encoding='utf-8')
    f.flush()
    json.dump(queryAllWithType(0, 10000, filterMobileReports), f, ensure_ascii=False, indent=4)
    f.close()