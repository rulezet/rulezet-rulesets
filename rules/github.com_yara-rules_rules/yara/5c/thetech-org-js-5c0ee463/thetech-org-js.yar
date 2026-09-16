rule thetech_org_js {
    strings: $ = "|RegExp|onepage|checkout|"
    condition: any of them
}