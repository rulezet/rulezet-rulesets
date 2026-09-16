rule IOS_canary {
  meta:
    author      = "Didier Stevens (https://DidierStevens.com)"
    description = "Search for a Cisco IOS canary value"
    method      = "Find canary sequence FD0110DF"

  strings:
    $canary = { FD 01 10 DF }

  condition:
    $canary
}