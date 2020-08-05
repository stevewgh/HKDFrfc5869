namespace HKDFrfc5869.Tests
{
    using HKDFrfc5869;
    using Xunit;

    public class HKDFTests
    {
        [Theory]
        [ClassData(typeof(Rfc5869TestCases))]
        public void TestCases(TestCaseData testCaseData)
        {
            using var hkdf = new HKDF(testCaseData.Algorithm);
            var actualKeyingMaterial = hkdf.DeriveKey(testCaseData.InitialKeyingMaterial, testCaseData.Salt, testCaseData.Info, testCaseData.Length);

            Assert.Equal(testCaseData.ExpectedKeyingMaterial, actualKeyingMaterial.ToArray());
        }
    }
}