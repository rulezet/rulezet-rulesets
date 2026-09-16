rule TTP_XOR_WriteProcessMemory_edc7 {
  strings:
    $key_edc7 = { ba b5 [2] 88 97 [2] 8e a2 [2] a0 a2 [2] 9f be }

  condition:
    any of them
}