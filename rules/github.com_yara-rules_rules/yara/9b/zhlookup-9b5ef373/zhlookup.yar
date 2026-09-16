rule zhLookUp
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhLookUp.Properties"

  condition:
    all of them
}