rule WanaCrypt0r
{
meta:
  description = "Detects artifacts from WanaCrypt0r Ransomware"
  author = "Kiran Bandla - iDefense"
  reference = "https://s3.amazonaws.com/assets.accenture.com/PDF/Accenture-Security-Ransomware.pdf"
strings:
  $a = "WanaDecryptor"
  $b = "Wana Decrypt0r"
  $c = "WanaCrypt0r"
  $d = ".wnry"
  $e = ".WNRY"
  $f = "bitcoin"
  $g = "vssadmin"
  $h = "torproject"
condition:
  4 of them
}