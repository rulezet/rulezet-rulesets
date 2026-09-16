rule TTP_XOR_WriteProcessMemory_58fd {
  strings:
    $key_58fd = { 0f 8f [2] 3d ad [2] 3b 98 [2] 15 98 [2] 2a 84 }

  condition:
    any of them
}