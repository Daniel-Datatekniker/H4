using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Hash
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Hmac hmc;
        private Rng rng;
        private byte[] key;
        private HashTypes selectedType;
        public MainWindow()
        {
            InitializeComponent();
            rng = new Rng();
            foreach (HashTypes htype in (HashTypes[])Enum.GetValues(typeof(HashTypes)))
                SelectHash.Items.Add(htype);

            SelectHash.SelectionChanged += SelectHash_SelectionChanged1;
        }

        private void SelectHash_SelectionChanged1(object sender, SelectionChangedEventArgs e)
        {
            if (((ComboBox)sender).SelectedItem != null)
            {
                BtnComputeMac.IsEnabled = true;
                selectedType = (HashTypes)SelectHash.SelectedItem;
            }
            else
                BtnComputeMac.IsEnabled = false;
        }

        private void BtnComputeMac_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(InputMsg.Text) && !string.IsNullOrEmpty(InputKey.Text))
            {
                Messenger.Content = "";
                key = rng.KeyGenerator(Int32.Parse(InputKey.Text));
                hmc = new Hmac(selectedType, key);
                var computedResult = hmc.computeHmac(selectedType, hmc.EncodeUtf8(InputMsg.Text), key);
                InputMacHex.Text = BitConverter.ToString(computedResult);
                InputMacAsci.Text = Convert.ToBase64String(computedResult);
                BtnVerifyMac.IsEnabled = true;
            }
            else
                BtnVerifyMac.IsEnabled = false;
        }
        private void NumberValidationTextBox(object sender, TextCompositionEventArgs e)
        {
            Regex regex = new Regex("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }

        private void BtnVerifyMac_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(InputMacHex.Text))
            {
                byte[] nb = Convert.FromBase64String(InputMacAsci.Text);
                if (hmc.CheckAuthority(hmc.EncodeUtf8(InputMsg.Text), nb, key))
                    Messenger.Content = "Authority is ok!";
                else
                    Messenger.Content = "Authority is not ok...";
            }
        }
    }
}
