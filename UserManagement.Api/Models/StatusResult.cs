namespace UserManagement.Api.Models
{
    public class StatusResult
    {
        public StatusResult(int statusCode, object value = null)
        {
            StatusCode = statusCode;
            Value = value;
        }

        public int StatusCode { get; set; }
        public object Value { get; set; }
    }
}
