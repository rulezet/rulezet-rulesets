rule TTP_XOR_WriteProcessMemory_fcfe {
  strings:
    $key_fcfe = { ab 8c [2] 99 ae [2] 9f 9b [2] b1 9b [2] 8e 87 }

  condition:
    any of them
}