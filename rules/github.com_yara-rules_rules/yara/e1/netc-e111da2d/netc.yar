rule NetC
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"

  condition:
    all of them
}