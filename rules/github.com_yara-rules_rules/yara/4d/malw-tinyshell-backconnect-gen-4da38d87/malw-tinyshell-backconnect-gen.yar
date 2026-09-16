rule MALW_TinyShell_backconnect_Gen {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 condition:
    ((is__elf) or  (is__osx))
    and priv01
    and priv02
    and filesize < 100KB
}