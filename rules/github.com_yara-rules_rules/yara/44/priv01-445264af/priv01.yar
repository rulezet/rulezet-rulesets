rule priv01 {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 strings:
    $vara01 = { 73 3A 70 3A 00 }
    $vara02 = "Usage: %s" fullword nocase wide ascii
    $vara03 = "[ -s secret ]" fullword nocase wide ascii
    $vara04 = "[ -p port ]" fullword nocase wide ascii
 condition:
    all of them
}