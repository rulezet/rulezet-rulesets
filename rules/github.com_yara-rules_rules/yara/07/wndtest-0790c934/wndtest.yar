rule wndTest
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

  condition:
    all of them
}