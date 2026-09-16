rule TTP_XOR_WriteProcessMemory_3943 {
  strings:
    $key_3943 = { 6e 31 [2] 5c 13 [2] 5a 26 [2] 74 26 [2] 4b 3a }

  condition:
    any of them
}