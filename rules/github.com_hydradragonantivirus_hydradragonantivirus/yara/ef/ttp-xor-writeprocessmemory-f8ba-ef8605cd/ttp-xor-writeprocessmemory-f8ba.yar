rule TTP_XOR_WriteProcessMemory_f8ba {
  strings:
    $key_f8ba = { af c8 [2] 9d ea [2] 9b df [2] b5 df [2] 8a c3 }

  condition:
    any of them
}