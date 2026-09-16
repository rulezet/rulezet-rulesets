rule TTP_XOR_WriteProcessMemory_ddfd {
  strings:
    $key_ddfd = { 8a 8f [2] b8 ad [2] be 98 [2] 90 98 [2] af 84 }

  condition:
    any of them
}