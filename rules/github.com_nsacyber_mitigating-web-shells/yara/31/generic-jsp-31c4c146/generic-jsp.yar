rule generic_jsp
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}