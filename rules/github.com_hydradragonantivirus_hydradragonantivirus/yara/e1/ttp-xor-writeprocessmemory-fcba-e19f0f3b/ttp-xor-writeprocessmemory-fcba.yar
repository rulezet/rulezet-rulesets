rule TTP_XOR_WriteProcessMemory_fcba {
  strings:
    $key_fcba = { ab c8 [2] 99 ea [2] 9f df [2] b1 df [2] 8e c3 }

  condition:
    any of them
}