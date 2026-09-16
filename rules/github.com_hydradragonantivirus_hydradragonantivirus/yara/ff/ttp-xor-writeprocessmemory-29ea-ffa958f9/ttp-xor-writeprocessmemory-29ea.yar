rule TTP_XOR_WriteProcessMemory_29ea {
  strings:
    $key_29ea = { 7e 98 [2] 4c ba [2] 4a 8f [2] 64 8f [2] 5b 93 }

  condition:
    any of them
}