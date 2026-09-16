rule includepicture_http {
  meta:
    author = "Didier Stevens (https://DidierStevens.com)"

  strings:
    $a1 = "INCLUDEPICTURE"
    $a2 = "http" nocase

  condition:
    $a1 and $a2
}