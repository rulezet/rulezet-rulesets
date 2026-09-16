rule eval
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}