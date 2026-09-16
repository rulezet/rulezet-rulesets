rule TTP_XOR_WriteProcessMemory_fcb3 {
  strings:
    $key_fcb3 = { ab c1 [2] 99 e3 [2] 9f d6 [2] b1 d6 [2] 8e ca }

  condition:
    any of them
}