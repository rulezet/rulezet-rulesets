rule MALW_TinyShell_backconnect_ELF {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 condition:
    is__elf
    and priv01
    and ((priv02)
      or ((priv03)
        or (priv04)))
    and filesize < 100KB
}