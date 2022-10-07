import requests

cookies = {
    'amp_6f2e4b': 'pNsGWYmRQccgY4orFK8drP...1geof4f77.1geof8th4.b3.0.b3',
    'TNS_SESSIONID': '91dcdc10e3a7cfa65021dc5a39cfd24a',
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    # Already added when you pass json=
    # 'Content-Type': 'application/json',
    'X-SecurityCenter': '312171197',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://localhost:8443',
    'Connection': 'keep-alive',
    'Referer': 'https://localhost:8443/',
    # Requests sorts cookies= alphabetically
    # 'Cookie': 'amp_6f2e4b=pNsGWYmRQccgY4orFK8drP...1geof4f77.1geof8th4.b3.0.b3; TNS_SESSIONID=91dcdc10e3a7cfa65021dc5a39cfd24a',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

json_data = {
    'query': {
        'name': '',
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'listvuln',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 50,
        'filters': [
            {
                'id': 'ip',
                'filterName': 'ip',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': '192.168.48.97',
            },
            {
                'id': 'dnsName',
                'filterName': 'dnsName',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': 'windows81.dc.demo.io',
            },
            {
                'id': 'repository',
                'filterName': 'repository',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': [
                    {
                        'id': '1',
                    },
                ],
            },
        ],
        'vulnTool': 'listvuln',
    },
    'sourceType': 'cumulative',
    'columns': [],
    'type': 'vuln',
}

response = requests.post('https://localhost:8443/rest/analysis', cookies=cookies, headers=headers, json=json_data)

