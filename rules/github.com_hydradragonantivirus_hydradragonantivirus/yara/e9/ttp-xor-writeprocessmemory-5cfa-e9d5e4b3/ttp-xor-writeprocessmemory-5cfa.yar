rule TTP_XOR_WriteProcessMemory_5cfa {
  strings:
    $key_5cfa = { 0b 88 [2] 39 aa [2] 3f 9f [2] 11 9f [2] 2e 83 }

  condition:
    any of them
}