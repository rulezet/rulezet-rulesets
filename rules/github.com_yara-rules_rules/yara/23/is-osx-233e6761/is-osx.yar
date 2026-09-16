rule is__osx
{
 meta:
    date = "2018-02-12"
    author = "@unixfreaxjp"
 condition:
    uint32(0) == 0xfeedface     or uint32(0) == 0xcafebabe
    or uint32(0) == 0xbebafeca  or uint32(0) == 0xcefaedfe
    or uint32(0) == 0xfeedfacf  or uint32(0) == 0xcffaedfe
}