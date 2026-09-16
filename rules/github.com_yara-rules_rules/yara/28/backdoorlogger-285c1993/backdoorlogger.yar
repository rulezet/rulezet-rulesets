rule BackDoorLogger
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "BackDoorLogger"
    $s2 = "zhuAddress"

  condition:
    all of them
}