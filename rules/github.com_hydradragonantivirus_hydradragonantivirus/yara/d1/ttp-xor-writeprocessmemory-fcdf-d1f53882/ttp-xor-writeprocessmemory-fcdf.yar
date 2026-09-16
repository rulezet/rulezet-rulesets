rule TTP_XOR_WriteProcessMemory_fcdf {
  strings:
    $key_fcdf = { ab ad [2] 99 8f [2] 9f ba [2] b1 ba [2] 8e a6 }

  condition:
    any of them
}