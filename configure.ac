AC_INIT([PyAppLauncher],[0.0.1])

AC_ARG_ENABLE(debug,
  [AC_HELP_STRING([--enable-debug],[Enable debug mode which you can check if PyAppLauncher works correctly.])],,
[\
case "${enableval}" in
 yes) enable_debug=yes ;;
 no)  enable_debug=no;;
esac],
enable_debug=no)

if test x"${enable_debug}" = x"yes"; then
  AC_SUBST([DEBUGOPT], "-DDEBUG")
else
  AC_SUBST([DEBUGOPT], "")
fi

AC_CONFIG_FILES([Makefile])

AC_OUTPUT