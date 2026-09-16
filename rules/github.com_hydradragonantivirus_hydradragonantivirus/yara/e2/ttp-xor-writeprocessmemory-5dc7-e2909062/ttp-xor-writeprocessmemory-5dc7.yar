rule TTP_XOR_WriteProcessMemory_5dc7 {
  strings:
    $key_5dc7 = { 0a b5 [2] 38 97 [2] 3e a2 [2] 10 a2 [2] 2f be }

  condition:
    any of them
}