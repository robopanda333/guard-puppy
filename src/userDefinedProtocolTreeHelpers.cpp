
#include "userDefinedProtocolTreeHelpers.h"


rangeEdit::rangeEdit(QWidget* parent): QWidget(parent)
{
    left = new QSpinBox(this);
    right = new QSpinBox(this);
    QHBoxLayout* layout = new QHBoxLayout();
    layout->setSpacing(0);
    layout->setMargin(0);
    setLayout(layout);
    layout->addWidget(left);
    layout->addWidget(right);
    left->setMinimum(0);
    left->setMaximum(65535);
    right->setMinimum(0);
    right->setMaximum(65535);
    QWidget::connect(left, SIGNAL(editingFinished()), this, SLOT(updateRightFromLeft()));
    QWidget::connect(right, SIGNAL(editingFinished()), this, SLOT(updateLeftFromRight()));
}
/*
void rangeEdit::updateAfromB(QSpinBox * A, QSpinBox * B)
{
    if
}
*/
void rangeEdit::setValue(int i, int j)
{
    left->setValue(i);
    right->setValue(j);
}
void rangeEdit::value(int& i, int& j)
{
    i = left->value();
    j = right->value();
}

UDPTreeDelegate::UDPTreeDelegate(GuardPuppyFireWall * firewall, QObject *parent):QItemDelegate(parent),fw(firewall)
{
}
UDPTreeDelegate::~UDPTreeDelegate()
{
}

QWidget * UDPTreeDelegate::createEditor(QWidget *parent, QStyleOptionViewItem const &, QModelIndex const & index) const
{
    QString string = index.model()->data(index, Qt::DisplayRole).toString();
    if(string=="")
        return (QWidget*)(void*)0;
    switch(index.column())
    {
        case 0: //lineEdit
        {
            QLineEdit* editor = new QLineEdit(parent);
            return editor;
        }
        case 1: //comboBox
        {
            QComboBox* editor = new QComboBox(parent);
            editor->addItem("TCP", QVariant(IPPROTO_TCP));
            editor->addItem("UDP", QVariant(IPPROTO_UDP));
            return editor;
        }
        case 2: //rangeEditWidget
        {
            rangeEdit* editor = new rangeEdit(parent);
            return editor;
        }
        case 3: //Combobox
        {
            QComboBox* editor = new QComboBox(parent);
            editor->addItem("Bidirectional", 1);
            editor->addItem("Unidirectional", 0);
            return editor;
        }
        default:
        {
            return (QWidget*)(void*)0;
        }
    }
}

void UDPTreeDelegate::setEditorData(QWidget * editor, QModelIndex const & index) const
{
     QString string = index.model()->data(index, Qt::DisplayRole).toString();
     if(!editor)
         return;
     switch(index.column())
     {
        case 0: //lineEdit
        {
            QLineEdit * edit = static_cast<QLineEdit *>(editor);
            edit->setText(string);
            return;
        }
        case 1: //comboBox
        {
            QComboBox * edit = static_cast<QComboBox *>(editor);
            edit->setCurrentIndex((string=="TCP")?0:1);
            return;
        }
        case 2: //rangeEditWidget
        {
            rangeEdit * edit = static_cast<rangeEdit *>(editor);
            std::string protocolName = index.model()->data(index.sibling(index.row(),0), Qt::DisplayRole).toString().toStdString();
            int start = fw->getStartPorts(protocolName)[index.row()];
            int end = fw->getEndPorts(protocolName)[index.row()];
            edit->setValue(start, end);
            return;
        }
        case 3: //comboBox
        {
            QComboBox * edit = static_cast<QComboBox *>(editor);
            edit->setCurrentIndex((string=="Bidirectional")?0:1);
            return;
        }
        default:
        {
        }
     }
     return;
}

void UDPTreeDelegate::applyToAllName(QString s, QAbstractItemModel * model, QModelIndex const & index) const
{
    QModelIndex const & parent = index.parent();
    if(!parent.isValid())
    {
        int i = 0;
        while(index.child(i,0).isValid())
        {
            model->setData(index.child(i,0), s, Qt::EditRole);
            model->setData(index.child(i,0), s, Qt::DisplayRole);
            ++i;
        }
        model->setData(index, s, Qt::EditRole);
        model->setData(index, s, Qt::DisplayRole);
        return;
    }
    else
    {
        int i = 0;
        while(parent.child(i,0).isValid())
        {
            model->setData(parent.child(i,0), s, Qt::EditRole);
            model->setData(parent.child(i,0), s, Qt::DisplayRole);
            ++i;
        }
        model->setData(parent, s, Qt::EditRole);
        model->setData(parent, s, Qt::DisplayRole);
        return;
    }
}

void UDPTreeDelegate::setModelData(QWidget * editor, QAbstractItemModel * model, QModelIndex const & index) const
{//this function needs to store data to the object model AND back to the database.
    if(!editor)
        return;
    QString protocolName = model->data(index.sibling(index.row(),0), Qt::DisplayRole).toString();
    switch(index.column())
    {
        case 0: //lineEdit
        {
            QLineEdit * line = static_cast<QLineEdit*>(editor);
            fw->setName( protocolName.toStdString(), line->text().toStdString());
            applyToAllName(line->text(), model, index);
            return;
        }
        case 1: //comboBox
        {
            QComboBox * combo = static_cast<QComboBox*>(editor);
            int curindex = combo->itemData(combo->currentIndex()).toInt();
            QString text= combo->currentText();
            fw->setType(protocolName.toStdString(), curindex, index.row());
            if(curindex == IPPROTO_TCP)
                dynamic_cast<QStandardItemModel*>(model)->itemFromIndex(index.sibling(index.row(), 3))->setFlags(0);
            else
                dynamic_cast<QStandardItemModel*>(model)->itemFromIndex(index.sibling(index.row(), 3))->setFlags(Qt::ItemIsEditable|Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            model->setData(index, curindex, Qt::EditRole);
            model->setData(index, text, Qt::DisplayRole);
            //set the firewall data here as well
            return;
        }
        case 2: //rangeEditWidget
        {
            rangeEdit* range = static_cast<rangeEdit*>(editor);
            int i, j;
            range->value(i,j);
            fw->setStartPort(protocolName.toStdString(), i, index.row());
            fw->setEndPort(protocolName.toStdString(), j, index.row());
            QString rangeString = fw->getRangeStrings(protocolName.toStdString())[index.row()].c_str();
            model->setData(index, rangeString, Qt::EditRole);//get the value from the protocol
            return;
        }
        case 3:
        {
            QComboBox * combo = static_cast<QComboBox*>(editor);
            int curindex = combo->itemData(combo->currentIndex()).toInt();
            QString text= combo->currentText();
            fw->setBidirectional(protocolName.toStdString(), curindex, index.row());
            model->setData(index, curindex, Qt::EditRole);
            model->setData(index, text, Qt::DisplayRole);
            return;
        }
        default:
        {
        }
    }
    return;
}
void UDPTreeDelegate::updateEditorGeometry(QWidget * editor, QStyleOptionViewItem const & option, QModelIndex const &) const
{
    if(!editor)
        return;
    editor->setGeometry(option.rect);
}

