rule MALW_TinyShell_backconnect_OSX {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 condition:
    is__osx
    and priv01
    and priv02
    and priv03
    and priv04
    and filesize < 100KB
}