/********************************************************************************
** Form generated from reading UI file 'widget.ui'
**
** Created by: Qt User Interface Compiler version 6.1.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WIDGET_H
#define UI_WIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLCDNumber>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Widget
{
public:
    QLCDNumber *lcdNumber;
    QPushButton *pbCoin500;
    QPushButton *pbCoin100;
    QPushButton *pbCoin50;
    QPushButton *pbCoffee;
    QPushButton *pbTea;
    QPushButton *pbMilk;
    QPushButton *pbReset;
    QPushButton *pbCoin10;

    void setupUi(QWidget *Widget)
    {
        if (Widget->objectName().isEmpty())
            Widget->setObjectName(QString::fromUtf8("Widget"));
        Widget->resize(800, 600);
        lcdNumber = new QLCDNumber(Widget);
        lcdNumber->setObjectName(QString::fromUtf8("lcdNumber"));
        lcdNumber->setGeometry(QRect(300, 40, 191, 111));
        pbCoin500 = new QPushButton(Widget);
        pbCoin500->setObjectName(QString::fromUtf8("pbCoin500"));
        pbCoin500->setGeometry(QRect(170, 190, 87, 27));
        pbCoin100 = new QPushButton(Widget);
        pbCoin100->setObjectName(QString::fromUtf8("pbCoin100"));
        pbCoin100->setGeometry(QRect(170, 240, 87, 27));
        pbCoin50 = new QPushButton(Widget);
        pbCoin50->setObjectName(QString::fromUtf8("pbCoin50"));
        pbCoin50->setGeometry(QRect(170, 290, 87, 27));
        pbCoffee = new QPushButton(Widget);
        pbCoffee->setObjectName(QString::fromUtf8("pbCoffee"));
        pbCoffee->setGeometry(QRect(470, 190, 87, 27));
        pbTea = new QPushButton(Widget);
        pbTea->setObjectName(QString::fromUtf8("pbTea"));
        pbTea->setGeometry(QRect(470, 240, 87, 27));
        pbMilk = new QPushButton(Widget);
        pbMilk->setObjectName(QString::fromUtf8("pbMilk"));
        pbMilk->setGeometry(QRect(470, 290, 87, 27));
        pbReset = new QPushButton(Widget);
        pbReset->setObjectName(QString::fromUtf8("pbReset"));
        pbReset->setGeometry(QRect(470, 390, 87, 27));
        pbCoin10 = new QPushButton(Widget);
        pbCoin10->setObjectName(QString::fromUtf8("pbCoin10"));
        pbCoin10->setGeometry(QRect(170, 340, 87, 27));

        retranslateUi(Widget);

        QMetaObject::connectSlotsByName(Widget);
    } // setupUi

    void retranslateUi(QWidget *Widget)
    {
        Widget->setWindowTitle(QCoreApplication::translate("Widget", "Widget", nullptr));
        pbCoin500->setText(QCoreApplication::translate("Widget", "500", nullptr));
        pbCoin100->setText(QCoreApplication::translate("Widget", "100", nullptr));
        pbCoin50->setText(QCoreApplication::translate("Widget", "50", nullptr));
        pbCoffee->setText(QCoreApplication::translate("Widget", "Coffee(200)", nullptr));
        pbTea->setText(QCoreApplication::translate("Widget", "Tea(150)", nullptr));
        pbMilk->setText(QCoreApplication::translate("Widget", "Milk(100)", nullptr));
        pbReset->setText(QCoreApplication::translate("Widget", "Reset", nullptr));
        pbCoin10->setText(QCoreApplication::translate("Widget", "10", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Widget: public Ui_Widget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WIDGET_H
