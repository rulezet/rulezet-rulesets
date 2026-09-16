rule TTP_XOR_WriteProcessMemory_2dfa {
  strings:
    $key_2dfa = { 7a 88 [2] 48 aa [2] 4e 9f [2] 60 9f [2] 5f 83 }

  condition:
    any of them
}