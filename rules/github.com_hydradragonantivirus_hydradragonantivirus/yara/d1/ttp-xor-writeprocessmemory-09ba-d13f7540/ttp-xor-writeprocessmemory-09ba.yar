rule TTP_XOR_WriteProcessMemory_09ba {
  strings:
    $key_09ba = { 5e c8 [2] 6c ea [2] 6a df [2] 44 df [2] 7b c3 }

  condition:
    any of them
}