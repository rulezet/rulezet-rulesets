rule TTP_XOR_WriteProcessMemory_0dc7 {
  strings:
    $key_0dc7 = { 5a b5 [2] 68 97 [2] 6e a2 [2] 40 a2 [2] 7f be }

  condition:
    any of them
}