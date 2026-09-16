event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    raw_uri_table[c$uid] = original_URI;
}