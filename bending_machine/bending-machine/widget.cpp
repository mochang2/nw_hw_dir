#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    setControl();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int coin)
{
    money += coin;
    ui->lcdNumber->display(money);
    setControl();
}

void Widget::setControl()
{
    ui->pbCoffee->setEnabled(money >= 200);
    ui->pbTea->setEnabled(money >= 150);
    ui->pbMilk->setEnabled(money >= 100);
    ui->pbReset->setEnabled(money > 0);
}


void Widget::on_pbCoin500_clicked()
{
    changeMoney(500);
}

void Widget::on_pbCoin100_clicked()
{
    changeMoney(100);
}

void Widget::on_pbCoin50_clicked()
{
    changeMoney(50);
}

void Widget::on_pbCoin10_clicked()
{
    changeMoney(10);
}

void Widget::on_pbCoffee_clicked()
{
    changeMoney(-200);
}

void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}

void Widget::on_pbMilk_clicked()
{
    changeMoney(-100);
}

void Widget::on_pbReset_clicked()
{
    int five_hundred = money / 500;
    money %= 500;
    int one_hundred = money / 100;
    money %= 100;
    int five_ten = money / 50;
    money %= 50;
    int one_ten = money / 10;
    QMessageBox qbox;
    qbox.setText("change 500: " + QString::number(five_hundred) +
                 ", 100: " + QString::number(one_hundred) +
                 ", 50: " + QString::number(five_ten) +
                 ", 10: " + QString::number(one_ten));
    qbox.exec();
    changeMoney(money * -1);
}













