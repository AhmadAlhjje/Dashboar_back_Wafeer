/** خطأ تطبيقي بكود ثابت ورسالة ورمز حالة — نفس شكل أخطاء واجهة وفير `{ success:false, error:{code,message,details} }`. */
export class AppError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
    public readonly details: unknown = null,
  ) {
    super(message);
    this.name = 'AppError';
  }
}
