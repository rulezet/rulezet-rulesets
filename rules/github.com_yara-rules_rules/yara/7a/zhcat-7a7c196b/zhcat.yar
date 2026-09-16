rule zhCat
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide

  condition:
    all of them
}