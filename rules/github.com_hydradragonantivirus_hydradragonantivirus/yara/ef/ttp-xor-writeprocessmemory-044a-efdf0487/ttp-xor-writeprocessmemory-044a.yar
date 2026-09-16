rule TTP_XOR_WriteProcessMemory_044a {
  strings:
    $key_044a = { 53 38 [2] 61 1a [2] 67 2f [2] 49 2f [2] 76 33 }

  condition:
    any of them
}