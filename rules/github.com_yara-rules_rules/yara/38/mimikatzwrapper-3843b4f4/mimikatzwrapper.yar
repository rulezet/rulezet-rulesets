rule mimikatzWrapper : Toolkit
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "mimikatzWrapper"
    $s2 = "get_mimikatz"

  condition:
    all of them
}