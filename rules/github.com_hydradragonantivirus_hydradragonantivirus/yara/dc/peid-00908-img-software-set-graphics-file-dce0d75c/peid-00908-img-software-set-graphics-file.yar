rule PEiD_00908_Img_Software_Set_graphics_file_ {
  meta:
    description = "[Img Software Set graphics file]"
    ep_only     = "false"

  strings:
    $a = "SCMI   1AT"

  condition:
    $a
}