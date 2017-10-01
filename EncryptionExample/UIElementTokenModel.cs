namespace EncryptionExample
{
    internal class UIElementTokenModel
    {
        public UIElementTokenModel() { }
        public int? ProcessNumber { get; set; }
        public int ProcessFunctionNumber { get; set; }
        public int? MenuItemNumber { get; set; }
        public int? ParentKeyNumber { get; set; }
        public bool AllowOverrideMaxRecords { get; set; } = false;

    }
}