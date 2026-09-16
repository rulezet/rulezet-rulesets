rule TTP_XOR_WriteProcessMemory_dd6a {
  strings:
    $key_dd6a = { 8a 18 [2] b8 3a [2] be 0f [2] 90 0f [2] af 13 }

  condition:
    any of them
}