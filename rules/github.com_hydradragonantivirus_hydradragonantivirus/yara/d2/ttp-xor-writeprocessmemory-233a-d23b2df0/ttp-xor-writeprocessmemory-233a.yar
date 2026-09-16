rule TTP_XOR_WriteProcessMemory_233a {
  strings:
    $key_233a = { 74 48 [2] 46 6a [2] 40 5f [2] 6e 5f [2] 51 43 }

  condition:
    any of them
}