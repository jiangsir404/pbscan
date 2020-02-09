def request(flow):
    """函数写法
    """
    # # 添加header
    # flow.response.headers["newheader"] = "foo"
    # # 重定向
    # if flow.request.pretty_host == "example.org":
    #     flow.request.host = "mitmproxy.org"
    # # 修改query值
    # flow.request.query["mitmproxy"] = "rocks"
    req = flow.request
    if flow.request.method.lower() == 'post':
        print(req.text)
        print(req.content)
        print(req.raw_content)
        print(req.headers)

