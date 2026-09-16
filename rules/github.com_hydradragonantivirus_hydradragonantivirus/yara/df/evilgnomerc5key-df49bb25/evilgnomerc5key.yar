rule EvilGnomeRC5Key {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $k1 = "sdg62_AS.sa$die3"

  condition:
    all of them
}