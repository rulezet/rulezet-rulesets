rule zhmimikatz
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"

  condition:
    all of them
}