rule TTP_XOR_WriteProcessMemory_f866 {
  strings:
    $key_f866 = { af 14 [2] 9d 36 [2] 9b 03 [2] b5 03 [2] 8a 1f }

  condition:
    any of them
}