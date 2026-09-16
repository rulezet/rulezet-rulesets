import "hash"
rule Cusaom: Blog {
  meta:
    generated = "2016-07-28T09:50:53.795037"

  condition:
    
    hash.sha1(0, filesize) == "deadbeaf"
}