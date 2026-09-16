rule SmartCopy2
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"

  condition:
    all of them
}