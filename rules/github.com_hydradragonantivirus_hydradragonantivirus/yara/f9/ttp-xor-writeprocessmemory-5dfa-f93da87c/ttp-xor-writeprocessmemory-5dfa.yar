rule TTP_XOR_WriteProcessMemory_5dfa {
  strings:
    $key_5dfa = { 0a 88 [2] 38 aa [2] 3e 9f [2] 10 9f [2] 2f 83 }

  condition:
    any of them
}