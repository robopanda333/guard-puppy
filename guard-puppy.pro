######################################################################
# Automatically generated by qmake (2.01a) Wed Jan 25 10:41:56 2012
######################################################################

TEMPLATE = app
TARGET = 
DEPENDPATH += . src
INCLUDEPATH += . src

CONFIG += debug

# This is hacked in, but I don't care right now
# but it shouldn't be this way
# Assume there are boost-dev files in /usr/include
# and the regex library is in /usr/lib/libboost_regex
# 

LIBS += -L/usr/lib -L/usr/lib64  -lboost_regex -lboost_filesystem -lboost_system

QT += core
QT += gui
QT += xml

# Input
HEADERS += src/aboutDialog_w.h
HEADERS += src/dialog_w.h

FORMS += src/aboutDialog.ui
FORMS += src/guardPuppy.ui

SOURCES += src/aboutDialog_w.cpp
SOURCES += src/dialog_w.cpp
SOURCES += src/guardPuppy.cpp
SOURCES += src/zoneImportStrategy.cpp

