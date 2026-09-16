rule INFO_PE_HttpSendHttpResponse_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendHttpResponse, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendHttpResponse" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}